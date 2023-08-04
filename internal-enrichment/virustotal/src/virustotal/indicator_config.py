# -*- coding: utf-8 -*-
"""Indicator config."""
from dataclasses import dataclass

from pycti import get_config_variable


@dataclass
class IndicatorConfig:
    """Class to store the Indicator config."""

    _VALID_CONFIGS = {"FILE", "IP", "DOMAIN", "URL"}

    threshold: int
    valid_minutes: int
    detect: bool

    @staticmethod
    def load_indicator_config(config: dict, config_type: str) -> "IndicatorConfig":
        """
        Load the configuration for a given indicator

        Parameters
        ----------
        config : dict
            Config to load.
        config_type : str
            Type of the config to load (`FILE`, `IP`, `DOMAIN`, `URL`)

        Returns
        -------
        IndicatorConfig
            Indicator config instance
        """
        if config_type not in IndicatorConfig._VALID_CONFIGS:
            raise ValueError(f"Config type {config_type} is not valid.")

        return IndicatorConfig(
            threshold=get_config_variable(
                f"VIRUSTOTAL_{config_type.upper()}_INDICATOR_CREATE_POSITIVES",
                ["virustotal", f"{config_type.lower()}_indicator_create_positives"],
                config,
                True,
                10
            ),
            valid_minutes=get_config_variable(
                f"VIRUSTOTAL_{config_type.upper()}_INDICATOR_VALID_MINUTES",
                ["virustotal", f"{config_type.lower()}_indicator_valid_minutes"],
                config,
                True,
                2880
            ),
            detect=get_config_variable(
                f"VIRUSTOTAL_{config_type.upper()}_INDICATOR_DETECT",
                ["virustotal", f"{config_type.lower()}_indicator_detect"],
                config,
                True
            ),
        )
