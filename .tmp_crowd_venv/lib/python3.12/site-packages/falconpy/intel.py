"""CrowdStrike Falcon Threat Intelligence API interface class.

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
# pylint: disable=C0302
from typing import Dict, Union
from ._util import force_default, process_service_request, handle_single_argument
from ._payload import generic_payload_list
from ._result import Result
from ._service_class import ServiceClass
from ._endpoint._intel import _intel_endpoints as Endpoints


class Intel(ServiceClass):
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

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_actor_entities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get info about actors that match provided FQL filters.

        Keyword arguments:
        fields -- The fields to return, or a predefined set of fields in the form of the collection
                  name surround by two underscores: __<collection_name>__. e.g. slug __full__.
                  Defaults to __basic__.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  actors                sub_type.name
                  actors.id             sub_type.slug
                  actors.name           tags
                  actors.slug           tags.id
                  actors.url            tags.slug
                  created_date          tags.value
                  description           target_countries
                  id                    target_countries.id
                  last_modified_date    target_countries.slug
                  motivations           target_countries.value
                  motivations.id        target_industries
                  motivations.slug      target_industries.id
                  motivations.value     target_industries.slug
                  name                  target_industries.value
                  name.raw              type
                  short_description     type.id
                  slug                  type.name
                  sub_type              type.slug
                  sub_type.id           url
                  animal_classifier
        limit -- The maximum number of actors to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date.desc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelActorEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelActorEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_indicator_entities(self: object,
                                 parameters: dict = None,
                                 **kwargs
                                 ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get info about indicators that match provided FQL filters.

        Keyword arguments:
        fields -- The fields to return, or a predefined set of fields in the form of the collection
                  name surround by two underscores: __<collection_name>__. e.g. slug __full__.
                  Defaults to __basic__.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  _marker               labels.name
                  actors                last_updated
                  deleted               malicious_confidence
                  domain_types          malware_families
                  id                    published_date
                  indicator             reports
                  ip_address_types      targets
                  kill_chains           threat_types
                  labels                type
                  labels.created_on     vulnerabilities
                  labels.last_valid_on  reports.slug
        include_deleted -- include both published and deleted indicators.
                           Boolean, defaults to False.
        include_relations -- include related indicators. Boolean, defaults to True.
        limit -- The maximum number of indicators to return. [integer, 1-50000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. published_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelIndicatorEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelIndicatorEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_report_entities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get info about reports that match provided FQL filters.

        Keyword arguments:
        fields -- The fields to return, or a predefined set of fields in the form of the collection
                  name surround by two underscores: __<collection_name>__. e.g. slug __full__.
                  Defaults to __basic__.
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  actors                              sub_type
                  actors.animal_classifier            sub_type.id
                  actors.id                           sub_type.name
                  actors.name                         sub_type.slug
                  actors.slug                         tags
                  actors.url                          tags.id
                  created_date                        tags.slug
                  description                         tags.value
                  id                                  target_countries
                  last_modified_date                  target_countries.id
                  malware                             target_countries.slug
                  malware.community_identifiers       target_countries.value
                  malware.family_name                 target_industries
                  malware.slug                        target_industries.id
                  motivations                         target_industries.slug
                  motivations.id                      target_industries.value
                  motivations.slug                    type
                  motivations.value                   type.id
                  name                                type.name
                  name.raw                            type.slug
                  short_description                   url
                  slug                                summary
        limit -- The maximum number of reports to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelReportEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelReportEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_actor_entities(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs
                           ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve specific actors using their actor IDs.

        Keyword arguments:
        fields -- The fields to return, or a predefined set of fields in the form of the collection
                  name surround by two underscores: __<collection_name>__. e.g. slug __full__.
                  Defaults to __basic__.
        ids -- One or more actor IDs. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelActorEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelActorEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_indicator_entities(self: object,
                               *args,
                               body: dict = None,
                               **kwargs
                               ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve specific indicators using their indicator IDs.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- ID(s) of the indicator entities to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelIndicatorEntities
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelIndicatorEntities",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_mitre_report(self: object,
                         parameters: dict = None,
                         **kwargs
                         ) -> Union[Union[Dict[str, Union[int, dict]], bytes], Result]:
        """Export Mitre ATT&CK information for a given actor.

        Keyword arguments:
        actor_id -- Actor ID, derived from the actor name. String.
        format -- Report format. Accepted options: 'CSV' or 'JSON'. String
        parameters - full parameters payload, not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetMitreReport
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMitreReport",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def mitre_attacks(self: object, *args, body: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve reports and observable IDs associated with the given actor and attacks.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- ID(s) of the indicator entities to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/PostMitreAttacks
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="PostMitreAttacks",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_malware_report(self: object,
                           *args,
                           parameters: dict = None,
                           **kwargs) -> Union[Dict[str, Union[int, dict]], bytes]:
        """Export Mitre ATT&CK information for a given malware family.

        Keyword arguments:
        id -- Malware family name. String.
              Malware family names should be in lower case with spaces, dots and
              slashes replaced with dashes.
        format -- Report format. String.  Supported values: CSV, JSON or JSON_NAVIGATOR.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetMalwareMitreReport
        """
        # If not specified, default to JSON.
        if not kwargs.get("format", None):
            parameters["format"] = "JSON"

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalwareMitreReport",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_malware_entities(self: object,
                             *args,
                             parameters: dict = None,
                             **kwargs) -> Union[Dict[str, Union[int, dict]], bytes]:
        """Get malware entities for specified ids.

        Keyword arguments:
        ids -- Malware family entities to retrieve. String or list of strings.
               Malware family names should be in lower case with spaces, dots and
               slashes replaced with dashes.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetMalwareEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetMalwareEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_report_pdf(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Return a Report PDF attachment.

        Keyword arguments:
        id -- One or more actor IDs. String or list of strings.
        ids -- The ID of the report you want to download as a PDF.
               This parameter is used only if no id parameter given. String.
        parameters - full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelReportPDF
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelReportPDF",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_malware_entities(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get malware entities that match provided FQL filters.

        Keyword arguments:
        offset -- Set the starting row number to return malware IDs from. Defaults to 0. Integer.
        limit -- Set the number of malware IDs to return. The value must be between 1 and 5000. Integer.
        sort -- Order fields in ascending or descending order. String.
                Ex: created_date|asc.
        filter -- Filter your query by specifying FQL filter parameters. String.
        q -- Perform a generic substring search across all fields. String.
        fields -- The fields to return. String or list of strings.
        parameters -- Full parameters payload dictionary. Not required if using other keywords.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryMalwareEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryMalwareEntities",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_report_entities(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve specific reports using their report IDs.

        Keyword arguments:
        fields -- The fields to return, or a predefined set of fields in the form of the collection
                  name surround by two underscores: __<collection_name>__. e.g. slug __full__.
                  Defaults to __basic__.
        ids -- One or more actor IDs. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelReportEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelReportEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_file(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Download earlier rule sets.

        Keyword arguments:
        format -- Choose the format you want the rule set in. Either zip or gzip. Defaults to zip.
        id -- One or more actor IDs. String or list of strings.
        parameters - full parameters payload, not required if id is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'id'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelRuleFile
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelRuleFile",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "id")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_latest_rule_file(self: object, *args, parameters: dict = None, **kwargs) -> object:
        """Download the latest rule set.

        Keyword arguments:
        if_none_match -- Download the latest rule set only if it doesn't have an ETag
                             matching the given ones. String.
        if_modified_since -- Download the latest rule set only if the rule was modified after this date.
                             http, ANSIC and RFC850 formats accepted. String.
        format -- Choose the format you want the rule set in. Either zip or gzip. Defaults to zip.
        parameters - full parameters payload, not required if other keywords are used.
        type -- The rule news report type. The following values are accepted:
                common-event-format         snort-suricata-update
                netwitness                  yara-changelog
                snort-suricata-changelog    yara-master
                snort-suricata-master       yara-update
                cql-master                  cql-changelog
                cql-update

        Arguments: When not specified, the first argument to this method is assumed to be 'type'.
                   All others are ignored.

        Returns: binary object on SUCCESS, dict object containing API response on FAILURE.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetLatestIntelRuleFile
        """
        headers = {}
        if kwargs.get("if_none_match", None):
            headers["If-None-Match"] = kwargs.get("if_none_match")
        if kwargs.get("if_modified_since", None):
            headers["If-Modified-Since"] = kwargs.get("if_modified_since")

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetLatestIntelRuleFile",
            keywords=kwargs,
            headers=headers,
            params=handle_single_argument(args, parameters, "type")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def get_rule_entities(self: object,
                          *args,
                          parameters: dict = None,
                          **kwargs
                          ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Retrieve details for rule sets for the specified ids.

        Keyword arguments:
        ids -- One or more actor IDs. String or list of strings.
        parameters - full parameters payload, not required if ids is provided as a keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetIntelRuleEntities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetIntelRuleEntities",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_actor_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get actor IDs that match provided FQL filters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  actors                sub_type.name
                  actors.id             sub_type.slug
                  actors.name           tags
                  actors.slug           tags.id
                  actors.url            tags.slug
                  created_date          tags.value
                  description           target_countries
                  id                    target_countries.id
                  last_modified_date    target_countries.slug
                  motivations           target_countries.value
                  motivations.id        target_industries
                  motivations.slug      target_industries.id
                  motivations.value     target_industries.slug
                  name                  target_industries.value
                  name.raw              type
                  short_description     type.id
                  slug                  type.name
                  sub_type              type.slug
                  sub_type.id           url
                  animal_classifier
        limit -- The maximum number of actors to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelActorIds
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelActorIds",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_indicator_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get indicators IDs that match provided FQL filters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  _marker               labels.name
                  actors                last_updated
                  deleted               malicious_confidence
                  domain_types          malware_families
                  id                    published_date
                  indicator             reports
                  ip_address_types      targets
                  kill_chains           threat_types
                  labels                type
                  labels.created_on     vulnerabilities
                  labels.last_valid_on  reports.slug
        include_deleted -- include both published and deleted indicators.
                           Boolean, defaults to False.
        include_relations -- include related indicators. Boolean, defaults to True.
        limit -- The maximum number of indicators to return. [integer, 1-50000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. published_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelIndicatorIds
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelIndicatorIds",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_mitre_attacks(self: object,
                            *args,
                            parameters: dict = None,
                            **kwargs
                            ) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get MITRE tactics and techniques for the given actor.

        Keyword arguments:
        id -- Actor ID, derived from the actor name. (Example: fancy-bear) String.
        ids -- The actor ID(derived from the actor's name) for which to retrieve a list of attacks.
               Example: fancy-bear. Multiple values are allowed. List of strings.
        parameters - full parameters payload, not required if using `id` keyword.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryMitreAttacks
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryMitreAttacks",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_mitre_attacks_for_malware(self: object,
                                        *args,
                                        parameters: dict = None,
                                        **kwargs) -> Union[Dict[str, Union[int, dict]], bytes]:
        """Get MITRE tactics and techniques for the given malware.

        Keyword arguments:
        ids -- Malware family entities to retrieve. String or list of strings.
               Malware family names should be in lower case with spaces, dots and
               slashes replaced with dashes.
        parameters - full parameters payload, not required if using other keywords.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryMitreAttacksForMalware
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryMitreAttacksForMalware",
            keywords=kwargs,
            params=handle_single_argument(args, parameters, "ids")
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_report_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get report IDs that match provided FQL filters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
                  Available filter parameters:
                  actors                              sub_type
                  actors.animal_classifier            sub_type.id
                  actors.id                           sub_type.name
                  actors.name                         sub_type.slug
                  actors.slug                         tags
                  actors.url                          tags.id
                  created_date                        tags.slug
                  description                         tags.value
                  id                                  target_countries
                  last_modified_date                  target_countries.id
                  malware                             target_countries.slug
                  malware.community_identifiers       target_countries.value
                  malware.family_name                 target_industries
                  malware.slug                        target_industries.id
                  motivations                         target_industries.slug
                  motivations.id                      target_industries.value
                  motivations.slug                    type
                  motivations.value                   type.id
                  name                                type.name
                  name.raw                            type.slug
                  short_description                   url
                  slug                                summary
        limit -- The maximum number of reports to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelReportIds
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelReportIds",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_rule_ids(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Search for rule IDs that match provided filter criteria.

        Keyword arguments:
        description -- substring match on the description field. List of strings.
        limit -- The maximum number of rule IDs to return. [integer, 1-5000] Defaults to 10.
        max_created_date -- Filter results to those created on or before a certain date. String.
        min_created_date -- Filter results to those created on or after a certain date. String.
        name -- search by rule title. List of strings.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date|asc).
        tags -- search for rule tags. List of strings.
        type -- The rule news report type. Required.
                The following values are accepted:
                common-event-format         snort-suricata-update
                netwitness                  yara-changelog
                snort-suricata-changelog    yara-master
                snort-suricata-master       yara-update
                cql-master                  cql-changelog
                cql-update

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryIntelReportIds
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryIntelRuleIds",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_malware(self: object, parameters: dict = None, **kwargs) -> Union[Dict[str, Union[int, dict]], Result]:
        """Get malware family names that match provided FQL filters.

        Keyword arguments:
        filter -- The filter expression that should be used to limit the results. FQL syntax.
        limit -- The maximum number of actors to return. [integer, 1-5000]
        offset -- The integer offset to start retrieving records from.
        parameters - full parameters payload, not required if using other keywords.
        q -- Perform a generic substring search across all fields.
        sort -- The property to sort by. FQL syntax (e.g. created_date|asc).

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryMalware
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryMalware",
            keywords=kwargs,
            params=parameters
            )

    @force_default(defaults=["body"], default_types=["dict"])
    def get_vulnerabilities(self: object, *args, body: dict = None, **kwargs) -> dict:
        """Retrieve specific vulnerabilities using their indicator IDs.

        Keyword arguments:
        body -- full body payload, not required when ids keyword is provided.
                {
                    "ids": [
                        "string"
                    ]
                }
        ids -- ID(s) of the indicator entities to retrieve. String or list of strings.

        Arguments: When not specified, the first argument to this method is assumed to be 'ids'.
                   All others are ignored.

        Returns: dict object containing API response.

        HTTP Method: POST

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/GetVulnerabilities
        """
        if not body:
            body = generic_payload_list(submitted_arguments=args,
                                        submitted_keywords=kwargs,
                                        payload_value="ids"
                                        )

        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="GetVulnerabilities",
            body=body,
            body_validator={"ids": list} if self.validate_payloads else None,
            body_required=["ids"] if self.validate_payloads else None
            )

    @force_default(defaults=["parameters"], default_types=["dict"])
    def query_vulnerabilities(self: object, parameters: dict = None, **kwargs) -> dict:
        """Search for rule IDs that match provided filter criteria.

        Keyword arguments:
        filter -- FQL query specifying the filter parameters. String.
                  Filter parameters include:
                    _all                            related_actors
                    affected_products.product       related_actors.animal_classifier
                    affected_products.vendor        related_actors.name
                    community_identifiers           related_reports.serial_id
                    cve                             related_reports.title
                    cvss_v3_base                    related_threats
                    cvss_v3_base.score              related_threats.name
                    cvss_v3_base.severity           severity
                    exploit_status                  updated_timestamp
                    publish_date
        limit -- The maximum number of IDs to return. Integer.
        offset -- The integer offset to start retrieving records from. Defaults to 0.
        parameters - full parameters payload, not required if using other keywords.
        q -- Match phrase_prefix query criteria; included fields:
             _all (all filter string fields indexed).
        sort -- The property to sort by. FQL syntax.

        This method only supports keywords for providing arguments.

        Returns: dict object containing API response.

        HTTP Method: GET

        Swagger URL
        https://assets.falcon.crowdstrike.com/support/api/swagger.html#/intel/QueryVulnerabilities
        """
        return process_service_request(
            calling_object=self,
            endpoints=Endpoints,
            operation_id="QueryVulnerabilities",
            keywords=kwargs,
            params=parameters
            )

    # These method names align to the operation IDs in the API but
    # do not conform to snake_case / PEP8 and are defined here for
    # backwards compatibility / ease of use purposes
    QueryIntelActorEntities = query_actor_entities
    QueryIntelIndicatorEntities = query_indicator_entities
    QueryIntelReportEntities = query_report_entities
    QueryVulnerabilities = query_vulnerabilities
    GetVulnerabilities = get_vulnerabilities
    GetIntelActorEntities = get_actor_entities
    GetIntelIndicatorEntities = get_indicator_entities
    GetMitreReport = get_mitre_report
    GetMalwareMitreReport = get_malware_report
    PostMitreAttacks = mitre_attacks
    GetMalwareEntities = get_malware_entities
    GetIntelReportPDF = get_report_pdf
    QueryMalwareEntities = query_malware_entities
    GetIntelReportEntities = get_report_entities
    GetIntelRuleFile = get_rule_file
    GetLatestIntelRuleFile = get_latest_rule_file
    GetIntelRuleEntities = get_rule_entities
    QueryMitreAttacks = query_mitre_attacks
    QueryMitreAttacksForMalware = query_mitre_attacks_for_malware
    QueryIntelActorIds = query_actor_ids
    QueryMalware = query_malware
    QueryIntelIndicatorIds = query_indicator_ids
    QueryIntelReportIds = query_report_ids
    QueryIntelRuleIds = query_rule_ids
