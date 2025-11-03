from pathlib import Path


def get_prompt(file_path: Path) -> dict[str, str]:
    prompt = """
Fix the content of {file_path}, according to the guidance and the instructions below.

Guidance:
    This tests suite defines unit tests for `main.py.tmp` (run by `pytest`).
    The fake data used as input must reflect the fields of the Pydantic models in `settings.py.tmp`.

Instructions:
    1. fix `StubConnectorSettings._load_config_dict` returned dict with accurate data
        - create a dict that is a valid input for `ConnectorSettings` model from `settings.py.tmp`
        - for each dict value, its type MUST correspond to the type of the pydantic field
        - for each dict value, if the corresponding env var is present in `docker-compse.yml`, cast it to the type of the pydantic field and use it
        - for each dict value, if the corresponding env var is missing in `docker-compose.yml` (or empty), fake a realistic value
        - the dict MUST at least contain all the fields that are required in the model (those without `default`)
        - use this dict to update the returned value of `_load_config_dict` method
        - in the returned value, DO NOT change the values for the keys `opencti` or `connector`
        - in the returned value, DO NOT change the name of the last key, it MUST remain the name of the last field in `ConnectorSettings` model in `settings.py.tmp`
        - in the returned value, replace the value of the last key by the one in the valid input dict you created
""".format(
        file_path=file_path
    )

    return {"role": "user", "content": prompt}
