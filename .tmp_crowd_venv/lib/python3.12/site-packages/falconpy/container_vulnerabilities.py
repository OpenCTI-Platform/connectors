"""CrowdStrike Falcon Container Vulnerabilities API interface class.

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
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._container_vulnerabilities import _container_vulnerabilities_endpoints as Endpoints


class ContainerVulnerabilities(ServiceClass):
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
    def read_vulnerability_counts_by_active_exploited(self: object,
                                                      parameters: dict = None,
                                                      **kwargs
                                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of vulnerabilities grouped by actively exploited.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilityCountByActivelyExploited
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilityCountByActivelyExploited",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerability_counts_by_cps_rating(self: object,
                                                parameters: dict = None,
                                                **kwargs
                                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of vulnerabilities grouped by csp_rating.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilityCountByCPSRating
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilityCountByCPSRating",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerability_counts_by_cvss_score(self: object,
                                                parameters: dict = None,
                                                **kwargs
                                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of vulnerabilities grouped by cvss score.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilityCountByCVSSScore
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilityCountByCVSSScore",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerability_counts_by_severity(self: object,
                                              parameters: dict = None,
                                              **kwargs
                                              ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of vulnerabilities grouped by severity.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. String.
        offset -- The offset from where to begin. String.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilityCountBySeverity
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilityCountBySeverity",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerability_count(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Aggregate count of vulnerabilities.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-vulnerabilities/ReadVulnerabilityCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilityCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerabilities_by_count(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top x vulnerabilities with the most impacted images.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters: cid, cve_id, registry, repository,tag
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilitiesByImageCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilitiesByImageCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vulnerabilities_by_pub_date(self: object,
                                         parameters: dict = None,
                                         **kwargs
                                         ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top x vulnerabilities with the most recent publication date.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters: cid, cve_id, registry, repository,tag
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadVulnerabilitiesPublicationDate
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadVulnerabilitiesPublicationDate",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_vulnerability_detail(self: object,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve vulnerability details related to an image.

        Keyword arguments:
        id -- Image UUID. String.
        filter -- Filter the vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported vulnerability filters:
                    cid                 exploited_status_name
                    cps_rating          is_zero_day
                    cve_id              remediation_available
                    cvss_score          severity
                    exploited_status    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadCombinedVulnerabilitiesDetails
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadCombinedVulnerabilitiesDetails",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_vulnerabilities_info(self: object,
                                           parameters: dict = None,
                                           **kwargs
                                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve vulnerability and package related info for this customer.

        Keyword arguments:
        cve_id -- Vulnerability CVE ID. String.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#
                /container-vulnerabilities/ReadCombinedVulnerabilitiesInfo
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadCombinedVulnerabilitiesInfo",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_vulnerabilities(self: object,
                                      parameters: dict = None,
                                      **kwargs
                                      ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve vulnerability and aggregate data filtered by the provided FQL.

        Keyword arguments:
        filter -- Filter vulnerabilities using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    base_os                     exploited_status_name
                    cid                         fix_status
                    container_id                image_digest
                    container_running_status    image_id
                    containers_impacted_range   images_impacted_range
                    cps_rating                  package_name_version
                    cve_id                      registry
                    cvss_score                  repository
                    description                 severity
                    exploited_status            tag
                    include_base_image_vuln
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:
                  cps_current_rating    images_impacted
                  cve_id                packages_impacted
                  cvss_score            severity
                  description
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-vulnerabilities/ReadCombinedVulnerabilities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadCombinedVulnerabilities",
            keywords=kwargs,
            params=parameters
            )

    ReadCombinedVulnerabilities = read_combined_vulnerabilities
    ReadCombinedVulnerabilitiesInfo = read_combined_vulnerabilities_info
    ReadCombinedVulnerabilitiesDetails = read_combined_vulnerability_detail
    ReadVulnerabilitiesPublicationDate = read_vulnerabilities_by_pub_date
    ReadVulnerabilitiesByImageCount = read_vulnerabilities_by_count
    ReadVulnerabilityCount = read_vulnerability_count
    ReadVulnerabilityCountBySeverity = read_vulnerability_counts_by_severity
    ReadVulnerabilityCountByCPSRating = read_vulnerability_counts_by_cps_rating
    ReadVulnerabilityCountByCVSSScore = read_vulnerability_counts_by_cvss_score
    ReadVulnerabilityCountByActivelyExploited = read_vulnerability_counts_by_active_exploited
    read_vulnerability_counts_by_actively_exploited = read_vulnerability_counts_by_active_exploited
