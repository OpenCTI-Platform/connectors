from falconpy import IOC as CrowdstrikeIOC

from .config_variables import ConfigCrowdstrike
from .constants import observable_type_mapper, platform_mapper, severity_mapper


class CrowdstrikeClient:
    """
    Working with Falcon Py for Crowdstrike API call
    """

    def __init__(self, helper):
        self.config = ConfigCrowdstrike()
        self.helper = helper
        self.cs = CrowdstrikeIOC(
            client_id=self.config.client_id,
            client_secret=self.config.client_secret,
            base_url=self.config.api_base_url,
        )

    def _handle_api_error(self, response: dict) -> None:
        """
        Handle API error from Crowdstrike
        :param response: Response in dict
        :return: None
        """
        if response["status_code"] >= 400:
            error_message = response["body"]["errors"][0]["message"]
            self.helper.connector_logger.error(
                "[API] Error while processing indicator",
                {"error_message": error_message},
            )

    def _search_indicator(self, ioc_value: str) -> list | None:
        """
        Search for existing indicator into Crowdstrike
        If data exist, return the ID of the resource
        :param ioc_value: IOC value in string
        :return: List of resources or None
        """
        try:

            cs_filter = f'value:"{ioc_value}"+created_by:"{self.config.client_id}"'

            response = self.cs.indicator_search(filter=cs_filter)
            self._handle_api_error(response)

            if response["status_code"] == 200:
                return response["body"]["resources"]

        except Exception as err:
            self.helper.connector_logger.error(
                "[API] Error while searching indicator", {"error_message": err}
            )

    @staticmethod
    def _parse_indicator_pattern(pattern: str) -> str:
        """
        Parse the indicator pattern got from stream
        :param pattern: Pattern of IOC in string
        :return: String of pattern parsed
        """
        return pattern.strip("[]").split(" ")[0]

    @staticmethod
    def _extract_indicator_value(pattern: str) -> str:
        """
        Extract the indicator value got from stream data pattern
        :param pattern: Pattern of IOC in string
        :return: String of IOC value extracted
        """
        return pattern.strip("[]").split(" ")[2].replace("'", "")

    def _map_indicator_type(self, pattern: str) -> str | None:
        """
        Map the indicator main observable type in OpenCTI with Crowdstrike IOC type
        :param pattern: Pattern of IOC in string
        :return: Observable type in string or None no map
        """
        ioc_pattern_type = self._parse_indicator_pattern(pattern)

        for obs_type in observable_type_mapper:
            if obs_type == ioc_pattern_type:
                return observable_type_mapper[obs_type]

        # If OpenCTI observable type is not in Crowdstrike
        return None

    def _map_severity(self, data: dict) -> str:
        """
        Map OpenCTI indicator score to severity value from Crowdstrike
        :param data: Data of IOC in dict
        :return: Severity value in string
        """
        indicator_score = self.helper.get_attribute_in_extension("score", data)

        for score_range in severity_mapper:
            if indicator_score in score_range:
                return severity_mapper[score_range]

    def _map_platform(self, data: dict) -> list | None:
        """
        Map OpenCTI indicator platforms to platform value from Crowdstrike
        :param data: Data of IOC in dict
        :return: List of platforms
        """
        indicator_platforms = self.helper.get_attribute_in_mitre_extension(
            "platforms", data
        )
        platforms = []

        # Only loop in available platforms, else continue
        for platform in platform_mapper:
            if indicator_platforms is not None and platform in indicator_platforms:
                if self.config.falcon_for_mobile_active:
                    platforms.append(platform_mapper[platform])
                elif platform not in ["ios", "android"]:
                    # If "Falcon for mobile" is not active in Crowdstrike
                    # API doesn't accept ["ios", "android"]
                    platforms.append(platform_mapper[platform])
                else:
                    self.helper.connector_logger.info(
                        "[API] Some value cannot be added or updated in Crowdstrike ",
                        {
                            "ioc_platforms_expected": ["windows", "mac", "linux"],
                            "ioc_platform_received": indicator_platforms,
                        },
                    )
                    continue

        if indicator_platforms is None:
            # If there is no platforms in OpenCTI
            # Add default platforms: "windows", "mac", "linux"
            platforms.extend(["windows", "mac", "linux"])

        if len(platforms) == 0:
            return None
        else:
            return platforms

    @staticmethod
    def _handle_labels(data: dict, event: str) -> None:
        """
        Handle labels in case permanent_delete configuration is False
        :param data: Data of IOC in dict
        :param event: Event in string
        :return: None
        """
        if event == "delete":
            if "labels" in data:
                labels = data["labels"]
                labels.append("TO_DELETE")
                data["labels"] = labels
            else:
                data["labels"] = ["TO_DELETE"]
        if event == "create":
            if "labels" in data:
                # Keep the new labels added, TO_DELETE is removed here
                labels = data["labels"]
                data["labels"] = labels
            else:
                # Remove TO_DELETE tag
                data["labels"] = []

    def _generate_indicator_body(
        self, data: dict, ioc_value: str, ioc_id: str = None
    ) -> dict | None:
        """
        Generate the body for Falcon Crowdstrike API call
        Required value: ioc_type, ioc_platforms, ioc_value
        :param data:
        :return: Body in dict or return None if required value is None
        """
        ioc_type = self._map_indicator_type(data["pattern"])

        # IOC type is required, return None if no type
        if ioc_type is not None:
            ioc_description = data.get("description", None)
            ioc_valid_until = data.get("valid_until", None)
            ioc_tags = data.get("labels", None)
            ioc_severity = self._map_severity(data)
            ioc_platforms = self._map_platform(data)

            indicator = {
                "action": "detect",  # "Detect only" on Falcon web UI
                "mobile_action": "detect",  # "Detect only" on Falcon web UI
                "type": ioc_type,
                "value": ioc_value,
                "severity": ioc_severity,
                "applied_globally": True,
                "source": "OpenCTI IOC",
            }

            # If description exists, add it in indicator to create in Crowdstrike
            if ioc_id is not None:
                indicator["id"] = ioc_id

            # If description exists, add it in indicator to create in Crowdstrike
            if ioc_description is not None:
                indicator["description"] = ioc_description

            # If valid_until value exists, add it in indicator to create in Crowdstrike
            if ioc_valid_until is not None:
                indicator["expiration"] = ioc_valid_until

            # If tags exist, add it in indicator to create in Crowdstrike
            if ioc_tags is not None:
                indicator["tags"] = ioc_tags

            # If platforms is added, add it in indicator to create in Crowdstrike
            if ioc_platforms is not None:
                indicator["platforms"] = ioc_platforms

            body = {"comment": "IOC imported from OpenCTI", "indicators": [indicator]}

            return body
        else:
            return None

    def create_indicator(self, data: dict, event: str | None = None) -> None:
        """
        Create IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :param event: Event in string or None
        :return: None
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs = self._search_indicator(ioc_value)

        # If IOC doesn't exist, create the IOC into Crowdstrike
        if len(ioc_cs) == 0:
            body = self._generate_indicator_body(data, ioc_value)

            if body is not None:
                response = self.cs.indicator_create(body=body)
                self._handle_api_error(response)

                if response["status_code"] == 201:
                    self.helper.connector_logger.info(
                        "[API] IOC successfully created in Crowdstrike",
                        {"ioc_value": ioc_value},
                    )
            else:
                self.helper.connector_logger.info(
                    "[API] IOC cannot be created in Crowdstrike",
                    {"ioc_value": ioc_value},
                )

        elif self.config.permanent_delete is False:
            self.update_indicator(data, event)

            self.helper.connector_logger.info(
                "[API] IOC already exists in Crowdstrike",
                {"ioc_value": ioc_value},
            )
        else:
            self.helper.connector_logger.info(
                "[API] IOC already exists in Crowdstrike",
                {"ioc_value": ioc_value},
            )

    def update_indicator(self, data: dict, event: str | None = None) -> None:
        """
        Update IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :param event: Event in string or None
        :return: None
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs = self._search_indicator(ioc_value)

        # If IOC exists, update the IOC into Crowdstrike
        if len(ioc_cs) != 0:

            # In case of permanent_delete is False
            # Update data with label TO_DELETE for Crowdstrike
            if self.config.permanent_delete is False:
                self._handle_labels(data, event)

            ioc_id = ioc_cs[0]
            body = self._generate_indicator_body(data, ioc_value, ioc_id)

            if body is not None:
                response = self.cs.indicator_update(body=body)
                self._handle_api_error(response)

                if response["status_code"] == 200:
                    self.helper.connector_logger.info(
                        "[API] IOC successfully updated in Crowdstrike",
                        {"ioc_value": ioc_value},
                    )
            else:
                self.helper.connector_logger.info(
                    "[API] IOC cannot be updated in Crowdstrike",
                    {"ioc_value": ioc_value},
                )

        else:
            self.helper.connector_logger.info(
                "[API] IOC doesn't exist in Crowdstrike",
                {"ioc_value": ioc_value},
            )

    def delete_indicator(self, data: dict) -> None:
        """
        Delete IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :return: None
        """
        ioc_value = self._extract_indicator_value(data["pattern"])
        ioc_cs = self._search_indicator(ioc_value)

        # If IOC exists and permanent_delete is True, delete the IOC into Crowdstrike
        if len(ioc_cs) != 0:
            ioc_id = ioc_cs[0]
            response = self.cs.indicator_delete(ioc_id)
            self._handle_api_error(response)

            if response["status_code"] == 200:
                self.helper.connector_logger.info(
                    "[API] IOC successfully deleted in Crowdstrike",
                    {"ioc_value": ioc_value},
                )

        else:
            self.helper.connector_logger.info(
                "[API] IOC doesn't exist in Crowdstrike",
                {"ioc_value": ioc_value},
            )
