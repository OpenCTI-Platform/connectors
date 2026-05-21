"""CrowdStrike Falcon Container Packages API interface class.

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
from ._endpoint._container_packages import _container_packages_endpoints as Endpoints


class ContainerPackages(ServiceClass):
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
    def read_packages_by_image_count(self: object,
                                     parameters: dict = None,
                                     **kwargs
                                     ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve the N most frequently used packages across images.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    ai_related              severity
                    cveid                   type
                    running_images          vulnerability_count
        limit -- The upper-bound on the number of records to retrieve. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesByImageCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesByImageCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_zero_day_counts(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs
                             ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve packages count affected by zero day vulnerabilities.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String. Supported filters: cid
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'filter'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesCountByZeroDay
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesCountByZeroDay",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "filter")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_fixable_vuln_count(self: object,
                                parameters: dict = None,
                                **kwargs
                                ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top x app packages with the most fixable vulnerabilities.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             license
                    container_id    package_name_version
                    cveid           severity
                    fix_status      type
                    image_digest    vulnerability_count
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesByFixableVulnCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesByFixableVulnCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_vuln_count(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve top x packages with the most vulnerabilities.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             license
                    container_id    package_name_version
                    cveid           severity
                    fix_status      type
                    image_digest    vulnerability_count
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesByVulnCount
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesByVulnCount",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined_export(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve packages identified by the provided filter criteria for the purpose of export.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             license
                    container_id    package_name_version
                    cveid           severity
                    fix_status      type
                    image_digest    vulnerability_count
        only_zero_day_affected -- Load zero day affected packages. Boolean. Defaults to False.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns: license, package_name_version, type
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesCombinedExport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesCombinedExport",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_combined(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve packages identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             license
                    container_id    package_name_version
                    cveid           severity
                    fix_status      type
                    image_digest    vulnerability_count
        only_zero_day_affected -- Load zero day affected packages. Boolean. Default is False.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:  license, package_name_version, type
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesCombined
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesCombined",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def read_packages(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve packages identified by the provided filter criteria.

        Keyword arguments:
        filter -- Filter packages using a query in Falcon Query Language (FQL). String.
                  Supported filters:
                    cid             license
                    container_id    package_name_version
                    cveid           severity
                    fix_status      type
                    image_digest    vulnerability_count
        only_zero_day_affected -- Load zero day affected packages. Boolean. Default is False.
        limit -- The upper-bound on the number of records to retrieve. Integer.
        offset -- The offset from where to begin. Integer.
        sort -- The fields to sort the records on. String.
                Supported columns:  license, package_name_version, type
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/container-packages/ReadPackagesCombinedV2
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="ReadPackagesCombinedV2",
            keywords=kwargs,
            params=parameters
            )

    ReadPackagesByImageCount = read_packages_by_image_count
    ReadPackagesCountByZeroDay = read_zero_day_counts
    ReadPackagesByFixableVulnCount = read_fixable_vuln_count
    ReadPackagesByVulnCount = read_vuln_count
    ReadPackagesCombinedExport = read_combined_export
    ReadPackagesCombined = read_combined
    ReadPackagesCombinedV2 = read_packages
