from falconpy import IOC as CrowdstrikeIOC

from .config_variables import ConfigCrowdstrike
from .constants import observable_type_mapper, severity_mapper


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
                "[API] Error while searching indicator",
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

    def _map_indicator_type(self, pattern: str) -> str:
        """
        Map the indicator main observable type in OpenCTI with Crowdstrike IOC type
        :param pattern: Pattern of IOC in string
        :return: Observable type in string
        """
        ioc_pattern_type = self._parse_indicator_pattern(pattern)

        for obs_type in observable_type_mapper:
            if obs_type == ioc_pattern_type:
                return observable_type_mapper[obs_type]

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

    def create_indicator(self, data: dict) -> None:
        """
        Create IOC from OpenCTI to Crowdstrike
        :param data: Data of IOC in dict
        :return: None
        """
        ioc_type = self._map_indicator_type(data["pattern"])
        ioc_value = data["name"]
        ioc_valid_until = data.get("valid_until", None)
        ioc_tags = data.get("labels", None)
        ioc_severity = self._map_severity(data)
        ioc_platforms = ["windows", "mac", "linux"]

        if self.config.falcon_for_mobile_active:
            ioc_platforms.extend(["ios", "android"])

        ioc_cs = self._search_indicator(ioc_value)

        # If IOC doesn't exist, create the IOC into Crowdstrike
        if len(ioc_cs) == 0:
            indicator = {
                "action": "detect",  # "Detect only" on Falcon web UI
                "mobile_action": "detect",  # "Detect only" on Falcon web UI
                "type": ioc_type,
                "value": ioc_value,
                "severity": ioc_severity,
                "platforms": ioc_platforms,
                "applied_globally": True,
                "source": "OpenCTI IOC",
            }

            # If valid_until value exists, add it in indicator to create in Crowdstrike
            if ioc_valid_until is not None:
                indicator["expiration"] = ioc_valid_until

            # If tags exist, add it in indicator to create in Crowdstrike
            if ioc_tags is not None:
                indicator["tags"] = ioc_tags

            body = {"comment": "IOC imported from OpenCTI", "indicators": [indicator]}

            response = self.cs.indicator_create(body=body)
            self._handle_api_error(response)

            if response["status_code"] == 201:
                self.helper.connector_logger.info(
                    "[API] IOC successfully created in Crowdstrike"
                )

        else:
            self.helper.connector_logger.info("[API] IOC already exist in Crowdstrike")

    def update_indicator(self, data: dict):
        ioc_value = data["name"]
        ioc_cs = self._search_indicator(ioc_value)

        if len(ioc_cs) != 0:
            response = self.cs.indicator_update()
        else:
            self.helper.connector_logger.info("[API] IOC doesn't exist in Crowdstrike")

    def delete_indicator(self, data):
        ioc_value = data["name"]
        ioc_cs = self._search_indicator(ioc_value)

        if len(ioc_cs) != 0:
            response = self.cs.indicator_delete()
        else:
            self.helper.connector_logger.info("[API] IOC doesn't exist in Crowdstrike")
