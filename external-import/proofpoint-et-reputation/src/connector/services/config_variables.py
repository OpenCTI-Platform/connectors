from pathlib import Path

import yaml
from connector.models import ProofpointEtReputationConfigVar
from pycti import get_config_variable
from pydantic import ValidationError


class ProofpointEtReputationConfig:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """
        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()

    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
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
        :return: None
        """

        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
            default="PT24H",
        )

        # Connector extra parameters
        self.api_token = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_API_TOKEN",
            ["proofpoint_et_reputation", "api_token"],
            self.load,
            required=True,
        )

        self.create_indicator = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_CREATE_INDICATOR",
            ["proofpoint_et_reputation", "create_indicator"],
            self.load,
            default=True,
        )

        self.min_score = get_config_variable(
            "PROOFPOINT_ET_REPUTATION_MIN_SCORE",
            ["proofpoint_et_reputation", "min_score"],
            self.load,
            default=20,
        )

        # Validation of environment variables
        try:
            global_variables_json = ProofpointEtReputationConfigVar.model_validate(
                dict(
                    # Required
                    api_token=self.api_token,
                    # Optional
                    duration_period=self.duration_period,
                    create_indicator=self.create_indicator,
                    min_score=self.min_score,
                )
            ).model_dump()

            # Re-assigning environment variables after Models
            for name_variable in global_variables_json:
                setattr(self, name_variable, global_variables_json[name_variable])

        except ValidationError as err:
            raise ValueError(err)
