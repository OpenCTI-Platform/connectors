# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector utilities module."""

from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

import pycountry
from pycti import OpenCTIConnectorHelper


class MalpediaUtils:
    """Initialize the utils"""

    def __init__(self, helper: OpenCTIConnectorHelper, interval_sec: int):
        self.helper = helper
        self.interval_sec = interval_sec

    def initiate_work_id(self, timestamp: int) -> str:
        """
        Initialize a work
        :param timestamp: Timestamp in integer
        :return: Work id in string
        """

        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] New work initiated...",
            {"work_id": work_id},
        )
        return work_id

    def load_state(self) -> Dict[str, Any]:
        current_state = self.helper.get_state()
        if not current_state:
            return {}
        return current_state

    @staticmethod
    def get_state_value(
        state: Optional[Mapping[str, Any]], key: str, default: Optional[Any] = None
    ) -> Any:
        if state is not None:
            return state.get(key, default)
        return default

    def is_scheduled(self, last_run: Optional[int], current_time: int) -> bool:
        if last_run is None:
            return True
        time_diff = current_time - last_run
        return time_diff >= self.interval_sec

    @staticmethod
    def check_version(last_version: Optional[int], current_version: int) -> bool:
        if last_version is None:
            return True
        return current_version > last_version

    @staticmethod
    def current_unix_timestamp() -> int:
        return int(datetime.utcnow().timestamp())

    @staticmethod
    def filter_countries_victims(all_victims: list) -> List:
        """
        This method allows you to filter all the victims (organization and country)
        and keep only the one that concerns a country.

        :param all_victims: This parameter includes all victims of types, organizations and countries.
        :return: list
        """

        list_of_countries_victims = []
        for victim in all_victims:
            try:
                pycountry.countries.lookup(victim)
                list_of_countries_victims.append(victim)
            except LookupError:
                continue
        return list_of_countries_victims

    def get_country_name(self, country_code: str) -> str:
        """
        This method allows you to retrieve the official name of the country based only on the country code.

        :param country_code: This parameter contains the country code.
        :return: str
        """
        try:
            country_info = pycountry.countries.get(alpha_2=country_code)
            if "official_name" in country_info:
                country_name = country_info.official_name
            else:
                country_name = country_info.name
            return country_name
        except Exception as e:
            return self.helper.connector_logger.error(
                "[ERROR] Some error occurred during get info country",
                {"country_code": country_code, "error": str(e)},
            )
