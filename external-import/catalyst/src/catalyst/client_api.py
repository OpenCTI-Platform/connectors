import datetime
from typing import Any, Dict, List

from python_catalyst import CatalystClient, PostCategory, TLPLevel


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.logger = helper.connector_logger
        self.config = config

        if (
            not self.config.api_key
            or self.config.api_key == "ChangeMe"
            or self.config.api_key == ""
        ):
            self.logger.warning("API key is not set. Public endpoint will be used.")
        # Initialize the CATALYST API client
        self.client = CatalystClient(
            api_key=self.config.api_key,
            base_url=self.config.api_base_url,
            logger=self.logger,
            create_observables=self.config.create_observables,
            create_indicators=self.config.create_indicators,
        )

    def get_entities(self) -> List[Dict]:
        """
        Get observables from the CATALYST API and convert them to STIX objects
        :return: A list of STIX objects
        """
        try:
            return self.get_member_contents()
        except Exception as err:
            self.logger.error(f"Error while fetching data: {str(err)}")
            return []

    def get_member_contents(self) -> List[Dict]:
        """
        Get member contents from the CATALYST API and convert them to STIX objects
        :return: A list of STIX objects
        """
        try:
            # Get the last run date to determine what to fetch
            last_run_datetime = None
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                try:
                    last_run_datetime = datetime.datetime.strptime(
                        current_state["last_run"], "%Y-%m-%d %H:%M:%S"
                    )
                    if last_run_datetime.tzinfo is None:
                        last_run_datetime = last_run_datetime.replace(
                            tzinfo=datetime.timezone.utc
                        )
                    self.logger.info(
                        f"Last run datetime: {last_run_datetime.isoformat()}"
                    )
                except ValueError:
                    self.logger.error(
                        f"Invalid last_run datetime format, fetching data for the last {self.config.sync_days_back} days"
                    )

            if last_run_datetime is None:
                sync_days_back = 365  # Default fallback
                if hasattr(self.config, "sync_days_back"):
                    sync_days_back = self.config.sync_days_back
                    if type(sync_days_back) == str:
                        sync_days_back = int(sync_days_back)
                last_run_datetime = datetime.datetime.now(
                    datetime.timezone.utc
                ) - datetime.timedelta(days=sync_days_back)

            self.logger.info(
                f"Fetching member contents updated since: {last_run_datetime.isoformat()}"
            )

            tlp_filters = self._parse_tlp_filters()

            category_filters = self._parse_category_filters()

            all_member_contents = []

            if not tlp_filters and not category_filters:
                self.logger.info(
                    "No specific TLP or category filters set. Fetching all member contents."
                )
                member_contents = self.client.get_updated_member_contents(
                    since=last_run_datetime, tlp=None, category=None
                )
                all_member_contents.extend(member_contents)
            else:
                # If only one filter is specified, iterate over it
                if tlp_filters and not category_filters:
                    for tlp in tlp_filters:
                        self.logger.info(
                            f"Fetching member contents with TLP filter: {tlp.value}"
                        )
                        member_contents = self.client.get_updated_member_contents(
                            since=last_run_datetime, tlp=[tlp], category=None
                        )
                        all_member_contents.extend(member_contents)

                # If only category filter is specified, iterate over it
                elif category_filters and not tlp_filters:
                    for category in category_filters:
                        self.logger.info(
                            f"Fetching member contents with category filter: {category.value}"
                        )
                        member_contents = self.client.get_updated_member_contents(
                            since=last_run_datetime, tlp=None, category=category
                        )
                        all_member_contents.extend(member_contents)

                else:
                    for tlp in tlp_filters:
                        for category in category_filters:
                            self.logger.info(
                                f"Fetching member contents with TLP: {tlp.value} and category: {category.value}"
                            )
                            member_contents = self.client.get_updated_member_contents(
                                since=last_run_datetime, tlp=[tlp], category=category
                            )
                            all_member_contents.extend(member_contents)

            unique_contents = {}
            for content in all_member_contents:
                content_id = content.get("id")
                if content_id and content_id not in unique_contents:
                    unique_contents[content_id] = content

            member_contents = list(unique_contents.values())

            self.logger.info(
                f"Retrieved {len(member_contents)} unique updated member contents from CATALYST API"
            )

            if not member_contents:
                self.logger.info("No updated member contents found.")
                return []

            stix_objects = []
            for content in member_contents:
                try:
                    report, related_objects = (
                        self.client.create_report_from_member_content(content)
                    )
                    if report:
                        stix_objects.append(report)
                    if related_objects:
                        stix_objects.extend(related_objects)
                except Exception as err:
                    self.logger.error(
                        f"Error processing content {content.get('id')}: {str(err)}"
                    )

            stix_objects.append(self.client.converter.identity)
            stix_objects.append(self.client.converter.tlp_marking)

            self.logger.info(
                f"Converted member contents to {len(stix_objects)} STIX objects"
            )

            return stix_objects

        except Exception as err:
            self.logger.error(f"Error while fetching member contents: {str(err)}")
            if hasattr(err, "response") and hasattr(err.response, "text"):
                self.logger.error(f"API response error: {err.response.text}")
            return []

    def _parse_tlp_filters(self) -> List[TLPLevel]:
        """
        Parse the TLP filter configuration.
        - If 'ALL' is specified, returns all TLP levels
        - If nothing is specified, returns an empty list (no filter)
        - Otherwise, returns a list of the specified TLP levels

        :return: List of TLPLevel enums
        """
        tlp_filters = []

        if hasattr(self.config, "tlp_filter") and self.config.tlp_filter:
            tlp_value = self.config.tlp_filter.strip().upper()

            if tlp_value == "ALL":
                self.logger.info(
                    "TLP filter set to ALL, will fetch content for all TLP levels"
                )
                return [TLPLevel.CLEAR, TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.RED]

            tlp_levels = tlp_value.split(",")
            for tlp in tlp_levels:
                tlp_name = tlp.strip().upper()
                if hasattr(TLPLevel, tlp_name):
                    tlp_filters.append(getattr(TLPLevel, tlp_name))
                    self.logger.debug(f"Added TLP filter: {tlp_name}")
                else:
                    self.logger.warning(f"Invalid TLP level: {tlp_name}")

        return tlp_filters

    def _parse_category_filters(self) -> List[PostCategory]:
        """
        Parse the category filter configuration.
        - If 'ALL' is specified, returns all categories
        - If nothing is specified, returns an empty list (no filter)
        - Otherwise, returns a list of the specified categories

        :return: List of PostCategory enums
        """
        category_filters = []

        if hasattr(self.config, "category_filter") and self.config.category_filter:
            category_value = self.config.category_filter.strip().upper()

            if category_value == "ALL":
                self.logger.info(
                    "Category filter set to ALL, will fetch content for all categories"
                )
                return [
                    PostCategory.DISCOVERY,
                    PostCategory.ATTRIBUTION,
                    PostCategory.RESEARCH,
                    PostCategory.FLASH_ALERT,
                ]

            categories = category_value.split(",")
            for cat in categories:
                cat_name = cat.strip().upper()
                if hasattr(PostCategory, cat_name):
                    category_filters.append(getattr(PostCategory, cat_name))
                    self.logger.debug(f"Added category filter: {cat_name}")
                else:
                    self.logger.warning(f"Invalid category: {cat_name}")

        return category_filters
