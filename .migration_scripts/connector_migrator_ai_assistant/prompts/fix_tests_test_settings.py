from pathlib import Path


def get_prompt(file_path: Path) -> dict[str, str]:
    prompt = """
Fix the content of {file_path}, according to the guidance and the instructions below.

Guidance:
    This tests suite defines unit tests for `settings.py.tmp` (run by `pytest`).
    The fake data used as input must reflect the fields of the Pydantic models in `settings.py.tmp`.

Instructions:
    1. in each `pytest.parametrize` decorator, fix the dict passed as first argument of `pytest.param` calls
        - create a dict that is a valid input for `ConnectorSettings` model from `settings.py.tmp`
        - for each dict value, its type MUST correspond to the type of the pydantic field
        - for each dict value, if the corresponding env var is present in `docker-compse.yml`, cast it to the type of the pydantic field and use it
        - for each dict value, if the corresponding env var is missing in `docker-compose.yml` (or empty), fake a realistic value
        - the dict MUST at least contain all the fields that are required in the model (those without `| None` annotation)
        - if the `id` argument of `pytest.param` is `full_valid_settings_dict`, the dict MUST contain ALL the fields defined in the model (required AND optional)
        - if the `id` argument of `pytest.param` is `minimal_valid_settings_dict`, the dict MUST contain ONLY the fields that are required in the model (those without `default`)
        - use this dict to update the first argument of `pytest.param` calls
        - in this first argument, DO NOT change the values for the keys `opencti` or `connector`
        - in this first argument, DO NOT change the name of the last key, it MUST remain the name of the last field in `ConnectorSettings` model in `settings.py.tmp`
        - in this first argument, replace the value of the last key by the one in the valid input dict you created
"""

    return {"role": "user", "content": prompt}
