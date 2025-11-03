from pathlib import Path


def get_prompt(file_path: Path) -> dict[str, str]:
    prompt = """
Fix the content of {file_path}, according to the guidance and the instructions below.

Guidance:
    This file contains the connector's main class, which defines the behavior of the application at runtime.
    Prefer to not remove methods, classes or variables declared outside the connector's main class to not break the application.

Instructions:
    1. keep the declarations of classes as is
        - DO NOT rename any classes
        - DO NOT change any classes' inheritance if any
    2. fix the body of `__init__` method of the connector's main class
        - DO NOT change the function's arguments
        - `self.config` MUST be assigned to `config` (from arguments) and never re-assigned
        - `self.helper` MUST be assigned to `helper` (from arguments) and never re-assigned
        - when the code refers to the whole config (e.g. `self.load` and `self.config`), replace by the whole `self.config`
    3. remove all `get_config_variable` method calls
        - replace `get_config_variable` calls by the accurate field in `self.config` (instance of `ConnectorSettings`)
        - refer to the env vars in `docker-compose.yml` and the models' fields in `settings.py.tmp` to get the accurate field
        - DO NOT use a field in `self.config` that is not declared in `settings.py.tmp`
        - if `get_config_variable` call can't be replaced by a field in `self.config`, replace by the default value specified in the call (5th argument - `None` by default)
        - if `get_config_variable` call can't be replaced by a field in `self.config`, replace by `os.environ.get(...)` with the first argument of the `get_config_variable` call
        - if `get_config_variable` call can be replaced by a field in `self.config` and that field can be `None`, add `or` with the default value specified in the call
        - replace `get_config_variable("CONNECTOR_UPDATE_EXISTING_DATA", ...)` by `False`
        - replace `get_config_variable("CONNECTOR_TYPE", ...)` by `self.config.connector.type`
    4. the connector's main class MUST contain an entrypoint method (a method that starts the connector, such as `run`, `main`, `start, etc)
        - if no entrypoint method exists, add one named `run`
        - the method SHOULD contain the same logic as in `if __name__ == '__main__'` if this statement is present
    5. remove `if __name__ == '__main__'` statement if present in the file
        - the file SHOULDN'T execute any code if run as standalone
        - the file SHOULD only execute code when called from `main.py.tmp`
""".format(
        file_path=file_path
    )

    return {"role": "user", "content": prompt}
