from pathlib import Path

import yaml
from connector.models import ProofpointEtReputationConfigVar
from pycti import get_config_variable
from pydantic import ValidationError


class ProofpointEtReputationConfig:
    def __init__(self):
        """Initialize the connector with necessary configurations"""
        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file

        Returns:
             dict: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[2] / "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if config_file_path.is_file()
            else {}
        )
        # We force the variable to be here EXTERNAL_IMPORT
        config.setdefault("connector", {}).update({"type": "EXTERNAL_IMPORT"})
        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables

        Returns:
            None
        """

        # Connector configurations
        self.connector_duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT24H",
        )

        # ProofPoint ET Reputation extra parameters
        self.extra_api_token = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_API_TOKEN",
            ["proofpoint_et_reputation", "api_token"],
            self.load,
            required=True,
        )

        self.extra_create_indicator = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_CREATE_INDICATOR",
            ["proofpoint_et_reputation", "create_indicator"],
            self.load,
            default=True,
        )

        self.extra_min_score = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_MIN_SCORE",
            ["proofpoint_et_reputation", "min_score"],
            self.load,
            default=20,
        )

        # Validation of environment variables
        try:
            global_variables_json = ProofpointEtReputationConfigVar.model_validate(
                dict(
                    # Connector parameters
                    connector_duration_period=self.connector_duration_period,  # OPTIONAL
                    # ProofPoint ET Reputation Extra parameters
                    extra_api_token=self.extra_api_token,  # REQUIRED
                    extra_create_indicator=self.extra_create_indicator,  # OPTIONAL
                    extra_min_score=self.extra_min_score,  # OPTIONAL
                )
            ).model_dump()

            prefixes = {"connector_": "connector", "extra_": "proofpoint_et_reputation"}

            # Re-assigning environment variables after Models
            for name_variable in global_variables_json:
                setattr(self, name_variable, global_variables_json[name_variable])

            # Re-assigning environment variables in self.load
            for key, value in global_variables_json.items():
                for prefix, section in prefixes.items():
                    if key.startswith(prefix):
                        new_key = key[len(prefix) :]
                        self.load.setdefault(section, {}).update({new_key: value})
                        break

        except ValidationError as err:
            raise ValueError(err)
